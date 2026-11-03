import hashlib
from ipaddress import IPv6Network, IPv6Address

from P4PCore.common.model.HashableEd25519PublicKey import HashableEd25519PublicKey

def ed25519PublicKeyToIp(publicKey:HashableEd25519PublicKey, prefix:str="fd00::", prefixLen:int=64) -> str:
    hashed = hashlib.sha256(publicKey.publicKeyBytes).digest()

    interfaceId = hashed[:8]
    net = IPv6Network(f"{prefix}/{prefixLen}", strict=False)

    prefixBytes = int(net.network_address).to_bytes(16, byteorder='big')[:8]
    
    ipBytes = prefixBytes + interfaceId
    
    ipAddr = IPv6Address(ipBytes)
    return str(ipAddr)