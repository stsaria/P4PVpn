import argparse
import asyncio
import json
import logging
import os
import secrets
import signal
from pathlib import Path
from collections.abc import Callable

from P4PCore.P4PRunner import P4PRunner
from P4PCore.common.model.Ed25519Signer import Ed25519Signer
from P4PCore.common.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.common.model.NodeIdentify import NodeIdentify
from P4PCore.plugin.append.nodeGossiper.NodeGossiper import NodeGossiper
from P4PCore.plugin.append.nodeGossiper.util.NodeIdentifyConverter import bytesToNodeIdentify, nodeIdentifyToBytes

from P4PVpn.P4PVpn import P4PVpn
from P4PVpn.util import AddrConverter


def _parseAddr(value:str) -> tuple[str, int]:
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
        if not separator:
            raise argparse.ArgumentTypeError("Use [ipv6]:port for IPv6 addresses.")
    else:
        host, separator, port = value.rpartition(":")
        if not separator or ":" in host:
            raise argparse.ArgumentTypeError("Use host:port or [ipv6]:port.")
    if not host:
        raise argparse.ArgumentTypeError("The address host cannot be empty.")
    try:
        portNumber = int(port)
    except ValueError as e:
        raise argparse.ArgumentTypeError("The address port must be an integer.") from e
    if not 1 <= portNumber <= 65535:
        raise argparse.ArgumentTypeError("The address port must be between 1 and 65535.")
    return host, portNumber


def _parsePublicKey(value:str) -> HashableEd25519PublicKey:
    try:
        publicKeyBytes = bytes.fromhex(value)
        if len(publicKeyBytes) != 32:
            raise ValueError
        return HashableEd25519PublicKey(publicKeyBytes)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            "The public key must be 32 bytes encoded as hexadecimal."
        ) from e


def _loadOrGeneratePrivateKey(path:Path) -> Ed25519Signer:
    if path.exists():
        try:
            privateKey = bytes.fromhex(path.read_text(encoding="ascii").strip())
            if len(privateKey) != 32:
                raise ValueError
            return Ed25519Signer(privateKey)
        except (OSError, UnicodeError, ValueError) as e:
            raise ValueError(f"{path} must contain a 32-byte hexadecimal private key.") from e

    privateKey = secrets.token_bytes(32)
    signer = Ed25519Signer(privateKey)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporaryPath = path.with_suffix(path.suffix + ".tmp")
    temporaryPath.write_text(
        privateKey.hex() + "\n",
        encoding="ascii",
    )
    os.chmod(temporaryPath, 0o600)
    temporaryPath.replace(path)
    return signer


def _parsePrivateKey(value:str) -> Ed25519Signer:
    try:
        privateKeyBytes = bytes.fromhex(value)
        if len(privateKeyBytes) != 32:
            raise ValueError
        return Ed25519Signer(privateKeyBytes)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            "The private key must be 32 bytes encoded as hexadecimal."
        ) from e


def _nodeFromConfig(value:dict) -> NodeIdentify:
    try:
        return NodeIdentify(
            ip=value["ip"],
            port=int(value["port"]),
            hashableEd25519PublicKey=_parsePublicKey(value["publicKey"]),
        )
    except (KeyError, TypeError, ValueError, argparse.ArgumentTypeError) as e:
        raise ValueError("Invalid node entry. Expected ip, port and publicKey.") from e


def _loadJson(path:Path) -> dict:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return value


def _ensureConfigFile(path:Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporaryPath = path.with_suffix(path.suffix + ".tmp")
    with temporaryPath.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "privateKeyFile": "p4pvpn-private-key",
                "tunName": "tun0",
                "nodeStateFile": "p4pvpn-nodes.json",
                "nodeStateIntervalSeconds": 10,
                "heartbeatIntervalSeconds": 5,
                "heartbeatTimeoutSeconds": 5,
                "listenHost": "127.0.0.1",
                "listenPort": 0,
                "logLevel": "INFO",
                "bootstrapNodes": [],
                "vpnPeerNodes": [],
            },
            file,
            indent=2,
        )
        file.write("\n")
    os.chmod(temporaryPath, 0o600)
    temporaryPath.replace(path)


def _loadNodes(path:Path) -> set[NodeIdentify]:
    value = _loadJson(path)
    nodes = set()
    for encodedNode in value.get("nodes", []):
        node = bytesToNodeIdentify(bytes.fromhex(encodedNode))
        if node is not None and node.ip and node.port:
            nodes.add(node)
    return nodes


def _saveNodes(path:Path, nodes:set[NodeIdentify]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporaryPath = path.with_suffix(path.suffix + ".tmp")
    value = {
        "nodes": sorted(
            nodeIdentifyToBytes(node).hex()
            for node in nodes
            if node.ip and node.port
        )
    }
    with temporaryPath.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2)
        file.write("\n")
    temporaryPath.replace(path)


def createArgumentParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a P4P IPv6 overlay VPN.")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Run the TUN send/receive simulation GUI.",
    )
    parser.add_argument("--configFile", type=Path, default=Path("p4pvpn-config.json"))
    parser.add_argument("--nodeStateFile", type=Path, default=Path("p4pvpn-nodes.json"))
    parser.add_argument("--privateKeyFile", type=Path, default=Path("p4pvpn-private-key"))
    parser.add_argument("--tunName", default="tun0")
    parser.add_argument("--nodeStateIntervalSeconds", type=float, default=10.0)
    parser.add_argument("--bootstrapNode", action="append", type=_parseAddr, default=[])
    parser.add_argument("--bootstrapNodePublicKey", action="append", type=_parsePublicKey, default=[])
    parser.add_argument("--peerPublicKey", action="append", type=_parsePublicKey, default=[])
    parser.add_argument("--privateKey", type=_parsePrivateKey, default=None)
    parser.add_argument("--listenHost", default="127.0.0.1")
    parser.add_argument("--listenPort", type=int, default=0)
    parser.add_argument("--heartbeatIntervalSeconds", type=float, default=5.0)
    parser.add_argument("--heartbeatTimeoutSeconds", type=float, default=5.0)
    parser.add_argument("--logLevel", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def _applyConfig(args:argparse.Namespace) -> argparse.Namespace:
    if args.configFile is None:
        return args
    config = _loadJson(args.configFile)
    for name in (
        "nodeStateFile",
        "privateKeyFile",
        "tunName",
        "nodeStateIntervalSeconds",
        "privateKey",
        "listenHost",
        "listenPort",
        "heartbeatIntervalSeconds",
        "heartbeatTimeoutSeconds",
        "logLevel",
    ):
        if name in config:
            setattr(args, name, config[name])
    if "privateKey" in config:
        args.privateKey = _parsePrivateKey(config["privateKey"])
    if "privateKeyFile" in config:
        args.privateKeyFile = Path(config["privateKeyFile"])
    if "nodeStateFile" in config:
        args.nodeStateFile = Path(config["nodeStateFile"])
    args.bootstrapNodes = [_nodeFromConfig(node) for node in config.get("bootstrapNodes", [])]
    args.peerPublicKey = [
        _parsePublicKey(publicKey)
        for publicKey in config.get("vpnPeerNodes", [])
    ]
    return args


async def _saveNodesLoop(nodeGossiper:NodeGossiper, path:Path, intervalSeconds:float) -> None:
    while True:
        await asyncio.sleep(intervalSeconds)
        _saveNodes(path, nodeGossiper.nodeIdentifies)


async def amain(
    args:argparse.Namespace,
    tunDevice=None,
    externalStopEvent=None,
    onVpnCreated:Callable[[P4PVpn], None] | None=None,
) -> None:
    _ensureConfigFile(args.configFile)
    if args.nodeStateIntervalSeconds <= 0:
        raise ValueError("nodeStateIntervalSeconds > 0")
    args = _applyConfig(args)
    if args.privateKey is None:
        args.privateKey = _loadOrGeneratePrivateKey(args.privateKeyFile)
    configBootstrapNodes = getattr(args, "bootstrapNodes", [])
    stateNodes = _loadNodes(args.nodeStateFile)
    if len(args.bootstrapNode) != len(args.bootstrapNodePublicKey):
        raise ValueError("Each bootstrapNode must have a bootstrapNodePublicKey.")
    bootstrapNodes = set(configBootstrapNodes)
    bootstrapNodes.update(
        NodeIdentify(
            ip=addr[0],
            port=addr[1],
            hashableEd25519PublicKey=publicKey,
        )
        for addr, publicKey in zip(args.bootstrapNode, args.bootstrapNodePublicKey)
    )
    registeredNodes = stateNodes | bootstrapNodes
    publicKeys = set(args.peerPublicKey) | {
        node.hashableEd25519PublicKey for node in bootstrapNodes
    }

    logging.basicConfig(
        level=getattr(logging, args.logLevel),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("P4PVpn").info(
        "Ed25519 public key: %s",
        args.privateKey.publicKey.publicKeyBytes.hex(),
    )
    logging.getLogger("P4PVpn").info(
        "Virtual IP: %s",
        AddrConverter.ed25519PublicKeyToIp(args.privateKey.publicKey),
    )
    runner = P4PRunner(
        ed25519Signer=args.privateKey,
        netV4ListeningAddr=(args.listenHost, args.listenPort),
    )
    nodeGossiper = NodeGossiper(
        runner
    )
    for node in registeredNodes:
        nodeGossiper.addNode(node)
    vpn = P4PVpn(
        runner,
        nodeGossiper,
        heartbeatIntervalSeconds=args.heartbeatIntervalSeconds,
        heartbeatTimeoutSeconds=args.heartbeatTimeoutSeconds,
        networksNodePublicKeys=publicKeys,
        tunDevice=tunDevice,
        tunName=args.tunName,
    )
    if onVpnCreated is not None:
        onVpnCreated(vpn)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    if externalStopEvent is None:
        for stopSignal in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(stopSignal, stopped.set)
            except NotImplementedError:
                pass
    saveTask = asyncio.create_task(
        _saveNodesLoop(nodeGossiper, args.nodeStateFile, args.nodeStateIntervalSeconds)
    )
    try:
        await vpn.begin()
        if externalStopEvent is None:
            await stopped.wait()
        else:
            while not externalStopEvent.is_set():
                await asyncio.sleep(0.1)
    finally:
        saveTask.cancel()
        await asyncio.gather(saveTask, return_exceptions=True)
        _saveNodes(args.nodeStateFile, nodeGossiper.nodeIdentifies)
        await vpn.end()

def main() -> None:
    args = createArgumentParser().parse_args()
    asyncio.run(amain(args))

if __name__ == "__main__":
    main()
