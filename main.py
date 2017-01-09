import asyncio
import logging


async def proxy(reader, writer, read_size=1024):
    lala = await reader.read(read_size)
    while lala:
        writer.write(lala)
        lala = await reader.read(read_size)
    writer.close()


async def serve(reader, writer, server_port=8001):
    s = writer.get_extra_info("socket")
    print("Got connection from {}".format(s.getpeername()))
    
    reader2, writer2 = await asyncio.open_connection(port=server_port)
    await asyncio.gather(
        *map(proxy, (reader, reader2), (writer2, writer))
    )
    print("connection closed")


def main():
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(asyncio.start_server(serve, port=8000))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.close()


if __name__ == '__main__':
    main()

