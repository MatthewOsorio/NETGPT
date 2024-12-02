from openai import OpenAI
from src.fileprocessor import fileprocessor
import sys

args =len(sys.argv)
if args < 2:
    print("Please add the file you would like to analyze in the command line.")
elif args > 2:
    print("Too many arguments. Please only add one file.")
else:
    gpt = OpenAI()
    file = fileprocessor(sys.argv[1])
    file.process()
    packets= str(file.getPackets())

    response = gpt.chat.completions.create(
        model= "gpt-4o",
        messages= [{"role": "system", "content": '''You are a network traffic analyzer
                                                    Your job is analyze and summarize this network traffic.
                                                    Also point out anything interesting, out of the ordinary, or any security concern'''
                    },
                    {"role": "user", "content": packets}]
    )

    print(response.choices[0].message.content)