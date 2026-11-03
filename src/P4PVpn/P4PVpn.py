import asyncio
from asyncio import Task
import uuid

from P4PCore.P4PRunner import P4PRunner
from P4PCore.plugin.append.nodeGossiper.NodeGossiper import NodeGossiper
from P4PCore.core.abstract.NetHandler import NetHandler
from P4PCore.common.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.common.model.NodeIdentify import NodeIdentify
from P4PCore.common.manager.Events import EventListener
from P4PCore.core.event.SecureNetStartedToHelloOnRecver import SecureNetStartedToHelloOnRecver
from P4PCore.core.event.SecureNetFinishedToHelloOnRecverEvent import SecureNetFinishedToHelloOnRecverEvent, SecureNetFinishedToHelloOnRecverEventResult
from P4PCore.plugin.append.nodeGossiper.event.NodeGossipRecvedEvent import NodeGossipRecvedEvent
from P4PCore.core.protocol.Protocol import SecurePacketElementSize, MAX_DATA_SIZE_ON_ENCRYPTED_AES_EXCLUDING_MAGIC

from P4PVpn.kernel.LinuxTunDevice import LinuxTunDevice
from P4PVpn.util import AddrConverter

VPN_PACKET_FLAG = uuid.UUID("c0f6b6cf-04d6-4f4a-9c95-4f770f7a8d1d").bytes

class P4PVpn(NetHandler):
    def __init__(
        self,
        runner:P4PRunner,
        nodeGossiper:NodeGossiper,
        heartbeatIntervalSeconds:float=5.0,
        heartbeatTimeoutSeconds:float=5.0,
        networksNodePublicKeys:set[HashableEd25519PublicKey] | None=None,
        tunDevice:LinuxTunDevice | None=None,
        tunName:str="tun0"
    ):
        if heartbeatIntervalSeconds <= 0:
            raise ValueError("heartbeatIntervalSeconds > 0")
        if heartbeatTimeoutSeconds <= 0:
            raise ValueError("heartbeatTimeoutSeconds > 0")

        self._runner:P4PRunner = runner
        self._nodeGossiper:NodeGossiper = nodeGossiper
        self._networksNodePublicKeys:set[HashableEd25519PublicKey] = set(networksNodePublicKeys or ())
        self._heartbeatIntervalSeconds:float = heartbeatIntervalSeconds
        self._heartbeatTimeoutSeconds:float = heartbeatTimeoutSeconds
        self._heartbeatTasks:dict[tuple[str, int], Task[None]] = {}
        self._secureConnectionTasks:dict[tuple[str, int], Task[None]] = {}
        self._virtualIpToNode:dict[str, NodeIdentify] = {}

        self._tunDevice:LinuxTunDevice = tunDevice or LinuxTunDevice(
            AddrConverter.ed25519PublicKeyToIp(self._runner.ed25519Signer.publicKey),
            self._onTunPacket,
            readBufferSize=(
                MAX_DATA_SIZE_ON_ENCRYPTED_AES_EXCLUDING_MAGIC
                -len(self._runner.magic)
                -SecurePacketElementSize.UUID
            ),
            ifname=tunName
        )
        self._runner.eventsManager.registerListener(self)
        if not self._runner.secureNet.registerHandler(self):
            raise Exception("Cannot register secure packet handler.")

    @property
    def networksNodePublicKeys(self) -> set[HashableEd25519PublicKey]:
        return self._networksNodePublicKeys

    @EventListener
    async def onSecureNetStartedToHello(self, e:SecureNetStartedToHelloOnRecver) -> None:
        if e.hashableEd25519PublicKey not in self._networksNodePublicKeys:
            raise Exception("for cancelling.")

    @EventListener
    async def onNodeGossipRecved(self, e:NodeGossipRecvedEvent) -> None:
        node = e.recvedNode
        if node is None or node.hashableEd25519PublicKey not in self._networksNodePublicKeys:
            return
        if node.addr in self._secureConnectionTasks:
            return

        task = asyncio.create_task(self._connectToNode(node))
        self._secureConnectionTasks[node.addr] = task
        task.add_done_callback(
            lambda completedTask, addr=node.addr: self._secureConnectionTasks.pop(addr, None)
            if self._secureConnectionTasks.get(addr) is completedTask
            else None
        )

    @EventListener
    async def onSecureNetFinishedToHello(self, e:SecureNetFinishedToHelloOnRecverEvent) -> None:
        if e.result != SecureNetFinishedToHelloOnRecverEventResult.SUCCESS:
            return

        publicKey = self._runner.secureNet.confirmedAddrsToEd25519PublicKeys.get(e.addr)
        if publicKey not in self._networksNodePublicKeys:
            return
        node = NodeIdentify(
            ip=e.addr[0],
            port=e.addr[1],
            hashableEd25519PublicKey=publicKey
        )
        self._virtualIpToNode[AddrConverter.ed25519PublicKeyToIp(publicKey)] = node

        if e.addr in self._heartbeatTasks:
            return

        task = asyncio.create_task(self._heartbeat(node))
        self._heartbeatTasks[e.addr] = task
        task.add_done_callback(
            lambda completedTask, addr=e.addr: self._heartbeatTasks.pop(addr, None)
            if self._heartbeatTasks.get(addr) is completedTask
            else None
        )

    async def _connectToNode(self, node:NodeIdentify) -> None:
        result = await self._runner.secureNet.hello(node)
        if result == self._runner.secureNet.HelloResult.SUCCESS:
            self._virtualIpToNode[
                AddrConverter.ed25519PublicKeyToIp(node.hashableEd25519PublicKey)
            ] = node
            if node.addr not in self._heartbeatTasks:
                task = asyncio.create_task(self._heartbeat(node))
                self._heartbeatTasks[node.addr] = task
                task.add_done_callback(
                    lambda completedTask, addr=node.addr: self._heartbeatTasks.pop(addr, None)
                    if self._heartbeatTasks.get(addr) is completedTask
                    else None
                )

    async def _heartbeat(self, node:NodeIdentify) -> None:
        while await self._runner.pingPongNet.ping(
            node.addr,
            timeoutSeconds=self._heartbeatTimeoutSeconds
        ) is not None:
            await asyncio.sleep(self._heartbeatIntervalSeconds)
        virtualIp = AddrConverter.ed25519PublicKeyToIp(node.hashableEd25519PublicKey)
        if self._virtualIpToNode.get(virtualIp) == node:
            self._virtualIpToNode.pop(virtualIp, None)
        self._runner.secureNet.bye(node)

    async def _onTunPacket(self, destIp:str, packet:bytes) -> None:
        node = self._virtualIpToNode.get(destIp)
        if node is None:
            return
        self._runner.secureNet.sendToSecure(
            VPN_PACKET_FLAG + packet,
            node
        )

    async def handle(self, data:bytes, _addr:tuple[str, int]) -> None:
        if data.startswith(VPN_PACKET_FLAG):
            data = data[len(VPN_PACKET_FLAG):]
        self._tunDevice.write(data)

    async def begin(self) -> None:
        await self._runner.begin()
        await self._nodeGossiper.begin()
        self._tunDevice.begin()

    async def end(self) -> None:
        tasks = tuple(self._heartbeatTasks.values()) + tuple(self._secureConnectionTasks.values())
        self._heartbeatTasks.clear()
        self._secureConnectionTasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tunDevice.end()
        await self._nodeGossiper.end()
        await self._runner.end()
