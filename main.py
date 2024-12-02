from openai import OpenAI
from src.fileprocessor import fileprocessor
import sys

gpt = OpenAI()
file = fileprocessor(sys.argv[1])
file.process()

response = gpt.chat.completions.create(
    model= "gpt-4o",
    messages= [{"role": "system", "content": "You are a network traffic analyzer. Your job is analyze and summarize. Also point out anything interesting, out of the ordinary, or a security concern.    "},
               {"role": "user", "content": str(file.getPackets())}]
)

print(response.choices[0].message.content)