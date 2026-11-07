"""Stand-in for an integration's API client (only its file path matters)."""


async def fetch(session, url):
    async with session.get(url) as resp:
        return await resp.text()
