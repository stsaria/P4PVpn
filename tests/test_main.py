import pytest

from P4PCore.common.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.common.model.NodeIdentify import NodeIdentify

from P4PVpn.__main__ import (
    _applyConfig,
    _loadNodes,
    _loadOrGeneratePrivateKey,
    _saveNodes,
    _ensureConfigFile,
    createArgumentParser,
)


def testArgumentParserAcceptsMultipleBootstrapNodesAndPublicKeys():
    args = createArgumentParser().parse_args([
        "--bootstrapNode",
        "[::1]:4000",
        "--bootstrapNode",
        "127.0.0.1:5000",
        "--bootstrapNodePublicKey",
        "00" * 32,
        "--bootstrapNodePublicKey",
        "11" * 32,
        "--peerPublicKey",
        "22" * 32,
    ])

    assert args.bootstrapNode == [("::1", 4000), ("127.0.0.1", 5000)]
    assert len(args.bootstrapNodePublicKey) == 2
    assert args.bootstrapNodePublicKey[0].publicKeyBytes == bytes(32)
    assert args.bootstrapNodePublicKey[1].publicKeyBytes == bytes([0x11]) * 32
    assert args.peerPublicKey[0].publicKeyBytes == bytes([0x22]) * 32


@pytest.mark.parametrize("value", ("127.0.0.1", "127.0.0.1:0", "[::1]4000"))
def testArgumentParserRejectsInvalidBootstrapNode(value:str):
    with pytest.raises(SystemExit):
        createArgumentParser().parse_args(["--bootstrapNode", value])


def testArgumentParserAcceptsPrivateKey():
    args = createArgumentParser().parse_args(["--privateKey", "22" * 32])

    assert args.privateKey.publicKey.publicKeyBytes


def testArgumentParserAcceptsTunName():
    args = createArgumentParser().parse_args(["--tunName", "p4p0"])

    assert args.tunName == "p4p0"


def testArgumentParserAcceptsGui():
    args = createArgumentParser().parse_args(["--gui"])

    assert args.gui


def testConfigPeerNodesContainOnlyPublicKeys(tmp_path):
    configPath = tmp_path / "config.json"
    configPath.write_text(
        '{"vpnPeerNodes": ["' + "33" * 32 + '"]}',
        encoding="utf-8",
    )
    args = createArgumentParser().parse_args(["--configFile", str(configPath)])

    args = _applyConfig(args)

    assert [key.publicKeyBytes for key in args.peerPublicKey] == [
        bytes([0x33]) * 32
    ]


def testPrivateKeyIsGeneratedAndReused(tmp_path):
    path = tmp_path / "private-key"

    firstSigner = _loadOrGeneratePrivateKey(path)
    secondSigner = _loadOrGeneratePrivateKey(path)

    assert firstSigner.publicKey == secondSigner.publicKey
    assert len(path.read_text(encoding="ascii").strip()) == 64
    assert path.stat().st_mode & 0o777 == 0o600


def testConfigFileIsGeneratedOnlyWhenMissing(tmp_path):
    path = tmp_path / "config.json"

    _ensureConfigFile(path)
    firstContent = path.read_text(encoding="utf-8")
    _ensureConfigFile(path)

    assert path.read_text(encoding="utf-8") == firstContent
    assert '"privateKeyFile": "p4pvpn-private-key"' in firstContent
    assert path.stat().st_mode & 0o777 == 0o600


def testNodeStateRoundTripUsesNodeIdentifyConverter(tmp_path):
    node = NodeIdentify(
        ip="127.0.0.1",
        port=4000,
        hashableEd25519PublicKey=HashableEd25519PublicKey(bytes(32)),
    )
    path = tmp_path / "nodes.json"

    _saveNodes(path, {node})

    assert _loadNodes(path) == {node}
