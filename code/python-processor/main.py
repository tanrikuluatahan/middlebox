import asyncio
import os
import random
import traceback
from nats.aio.client import Client as NATS
from scapy.all import Ether, IP

def parse_packet(data):
    # Try to parse with Ether or IP, raise Python exception if fails
    pkt = Ether(data)
    if IP in pkt:
        return pkt
    return IP(data)  # fallback to raw IP layer if Ether not present

def corrupt_packet(pkt, corruption_rate=0.0):
    if random.random() > corruption_rate:
        return pkt
    raw_bytes = bytearray(bytes(pkt))
    if len(raw_bytes) > 0:
        index = random.randint(0, len(raw_bytes) - 1)
        raw_bytes[index] ^= 0xFF
    return raw_bytes

async def run():
    nc = NATS()
    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        subject = msg.subject
        try:
            pkt = parse_packet(msg.data)
            pkt.show()
            await asyncio.sleep(random.expovariate(1 / 1e-8))
            corrupted = corrupt_packet(pkt, corruption_rate=0.0)
            out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
            await nc.publish(out_topic, bytes(corrupted))
        except Exception:
            traceback.print_exc()  # ⬅️ Native Python traceback
            os._exit(1)

    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print("Subscribed to inpktsec and inpktinsec topics")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    asyncio.run(run())
