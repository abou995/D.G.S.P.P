import discord
from discord.ext import commands
import aiohttp
import re
import os

# Récupération des variables d'environnement
TOKEN = os.getenv("DISCORD_TOKEN")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
USER_ID = int(os.getenv("USER_ID"))

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

# Liste de domaines suspects connus (à compléter si tu veux)
KNOWN_SUSPECT_DOMAINS = [
    "iplogger.org", "2no.co", "yip.su", "ipgrabber.ru", "iplogger.com", "blasze.com"
]

@bot.event
async def on_ready():
    print(f"Connecté en tant que {bot.user}")

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    if message.author.id == USER_ID and message.content.lower().startswith("scanne moi ce lien"):
        await message.channel.send("À vos ordres Monsieur.")

        urls = re.findall(r'(https?://\S+)', message.content)
        if not urls:
            await message.channel.send("Je n’ai trouvé aucun lien à analyser, Monsieur.")
            return

        for url in urls:
            # Vérification basique du nom de domaine
            if any(danger in url.lower() for danger in KNOWN_SUSPECT_DOMAINS):
                await message.channel.send(f"**Lien partiellement dangereux :**\n{url}\nPeut récupérer ton IP ou ta localisation.")
                continue  # on ne l'envoie pas à Google Safe Browsing

            async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
                safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
                json_body = {
                    "client": {
                        "clientId": "DGSPP",
                        "clientVersion": "1.0"
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                async with session.post(safe_browsing_url, json=json_body) as response:
                    result = await response.json()
                    if result.get("matches"):
                        await message.channel.send(f"**Alerte ⚠️ Lien suspect détecté :**\n{url}\nPour votre sécurité, évitez de cliquer.")
                    else:
                        await message.channel.send(f"Ce lien semble sûr, Monsieur.")

    await bot.process_commands(message)

# Lancement du bot
bot.run(TOKEN)
