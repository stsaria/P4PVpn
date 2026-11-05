import asyncio
from unittest.mock import AsyncMock

import pytest

from P4PCore.P4PRunner import P4PRunner
from P4PCore.common.model.NodeIdentify import NodeIdentify
from P4PCore.plugin.append.nodeGossiper.NodeGossiper import NodeGossiper
from P4PCore.plugin.append.nodeGossiper.event.NodeAddedToGossiperEvent import NodeAddedToGossiperEvent

from P4PVpn.P4PVpn import VPN_PACKET_FLAG, P4PVpn
from P4PVpn.util import AddrConverter


class MockTunDevice:
    def __init__(self):
        self.started = False
        self.ended = False
        self.writes = []

    def begin(self):
        self.started = True

    def end(self):
        self.ended = True

    def write(self, data: bytes):
        self.writes.append(data)


def _makeRealVpn(keySet=None, tunDevice=None):
    runner = P4PRunner()
    nodeGossiper = NodeGossiper(runner, syncIntervalSeconds=0.05)
    tun = tunDevice or MockTunDevice()
    vpn = P4PVpn(
        runner,
        nodeGossiper,
        heartbeatIntervalSeconds=0.1,
        heartbeatTimeoutSeconds=0.1,
        networksNodePublicKeys=set(keySet or ()),
        tunDevice=tun,
    )
    return runner, nodeGossiper, vpn, tun


@pytest.mark.asyncio
async def testBeginAndEndUseRealRunnerAndTunMock():
    runner, nodeGossiper, vpn, tun = _makeRealVpn()

    await runner.begin()
    await nodeGossiper.begin()
    await vpn.begin()
    await vpn.end()

    assert runner.net is not None
    assert nodeGossiper._checkAndAddNodeLoopTask is not None
    assert tun.started
    assert tun.ended


@pytest.mark.asyncio
async def testNodeDiscoveryEventStartsSecureHelloForAllowedPeer():
    seedRunner, seedGossiper, seedVpn, _ = _makeRealVpn()
    joiningRunner, joiningGossiper, joiningVpn, _ = _makeRealVpn({seedRunner.ed25519Signer.publicKey})
    seedVpn._networksNodePublicKeys.add(joiningRunner.ed25519Signer.publicKey)
    joiningVpn._networksNodePublicKeys.add(seedRunner.ed25519Signer.publicKey)

    await seedRunner.begin()
    await seedGossiper.begin()
    await joiningRunner.begin()
    await joiningGossiper.begin()
    await seedVpn.begin()
    await joiningVpn.begin()

    remoteNode = NodeIdentify(
        ip=seedRunner.net._protocolV4.transport.get_extra_info("sockname")[0],
        port=seedRunner.net._protocolV4.transport.get_extra_info("sockname")[1],
        hashableEd25519PublicKey=seedRunner.ed25519Signer.publicKey,
    )
    event = NodeAddedToGossiperEvent(remoteNode)

    joiningVpn.onNodeAddedToGossiper(event)
    await asyncio.sleep(0.3)

    assert joiningRunner.secureNet.confirmedAddrsToEd25519PublicKeys
    assert AddrConverter.ed25519PublicKeyToIp(seedRunner.ed25519Signer.publicKey) in joiningVpn._virtualIpToNode

    await joiningVpn.end()
    await seedVpn.end()
    await joiningGossiper.end()
    await seedGossiper.end()
    await joiningRunner.end()
    await seedRunner.end()


@pytest.mark.asyncio
async def testSecurePacketFromTunIsRoutedOverRealSecureNet():
    seedRunner, seedGossiper, seedVpn, seedTun = _makeRealVpn()
    joiningRunner, joiningGossiper, joiningVpn, _ = _makeRealVpn({seedRunner.ed25519Signer.publicKey})
    seedVpn._networksNodePublicKeys.add(joiningRunner.ed25519Signer.publicKey)
    joiningVpn._networksNodePublicKeys.add(seedRunner.ed25519Signer.publicKey)

    await seedRunner.begin()
    await seedGossiper.begin()
    await joiningRunner.begin()
    await joiningGossiper.begin()
    await seedVpn.begin()
    await joiningVpn.begin()

    remoteNode = NodeIdentify(
        ip=seedRunner.net._protocolV4.transport.get_extra_info("sockname")[0],
        port=seedRunner.net._protocolV4.transport.get_extra_info("sockname")[1],
        hashableEd25519PublicKey=seedRunner.ed25519Signer.publicKey,
    )
    assert await joiningRunner.secureNet.hello(remoteNode) == joiningRunner.secureNet.HelloResult.SUCCESS
    await asyncio.sleep(0.2)

    destIp = AddrConverter.ed25519PublicKeyToIp(seedRunner.ed25519Signer.publicKey)
    joiningVpn._virtualIpToNode[destIp] = remoteNode
    payload = b"hello-from-vpn"

    await joiningVpn._onTunPacket(destIp, payload)
    await asyncio.sleep(0.2)
    await seedVpn.handle(VPN_PACKET_FLAG + payload, remoteNode.addr)

    assert seedTun.writes.count(payload) >= 1

    await joiningVpn.end()
    await seedVpn.end()
    await joiningGossiper.end()
    await seedGossiper.end()
    await joiningRunner.end()
    await seedRunner.end()


@pytest.mark.asyncio
async def testHeartbeatFailureRemovesMappingAndDisconnects():
    seedRunner, seedGossiper, seedVpn, _ = _makeRealVpn()
    joiningRunner, joiningGossiper, joiningVpn, _ = _makeRealVpn({seedRunner.ed25519Signer.publicKey})
    seedVpn._networksNodePublicKeys.add(joiningRunner.ed25519Signer.publicKey)
    joiningVpn._networksNodePublicKeys.add(seedRunner.ed25519Signer.publicKey)

    await seedRunner.begin()
    await seedGossiper.begin()
    await joiningRunner.begin()
    await joiningGossiper.begin()
    await seedVpn.begin()
    await joiningVpn.begin()

    remoteNode = NodeIdentify(
        ip=seedRunner.net._protocolV4.transport.get_extra_info("sockname")[0],
        port=seedRunner.net._protocolV4.transport.get_extra_info("sockname")[1],
        hashableEd25519PublicKey=seedRunner.ed25519Signer.publicKey,
    )
    assert await joiningRunner.secureNet.hello(remoteNode) == joiningRunner.secureNet.HelloResult.SUCCESS
    await asyncio.sleep(0.2)

    joiningRunner.pingPongNet.ping = AsyncMock(return_value=None)
    joiningVpn._virtualIpToNode[AddrConverter.ed25519PublicKeyToIp(remoteNode.hashableEd25519PublicKey)] = remoteNode

    await joiningVpn._heartbeat(remoteNode)

    assert AddrConverter.ed25519PublicKeyToIp(seedRunner.ed25519Signer.publicKey) not in joiningVpn._virtualIpToNode

    await joiningVpn.end()
    await seedVpn.end()
    await joiningGossiper.end()
    await seedGossiper.end()
    await joiningRunner.end()
    await seedRunner.end()