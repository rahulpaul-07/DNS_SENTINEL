import pandas as pd
import random
import string

def generate_benign():
    prefixes = ["google", "github", "microsoft", "apple", "amazon", "netflix", "facebook", "twitter", "linkedin", "reddit", "stackoverflow", "wikipedia", "medium", "spotify", "adobe", "dropbox", "slack", "zoom", "discord", "twitch"]
    suffixes = ["com", "net", "org", "io", "dev", "ai", "co"]
    subdirs = ["", "api.", "mail.", "dev.", "static.", "cdn.", "assets."]
    
    benign = []
    for _ in range(500):
        domain = random.choice(subdirs) + random.choice(prefixes) + str(random.randint(1, 99)) + "." + random.choice(suffixes)
        benign.append(domain)
    return benign

def generate_dga():
    chars = string.ascii_lowercase + string.digits
    suffixes = ["com", "net", "org", "ru", "cn", "top", "xyz", "bit"]
    
    dga = []
    for _ in range(500):
        length = random.randint(15, 30)
        domain = "".join(random.choice(chars) for _ in range(length)) + "." + random.choice(suffixes)
        dga.append(domain)
    return dga

def create_dataset():>
    
    df = df.sample(frac=1).reset_index(drop=True)
    df.to_csv('dga_dataset.csv', index=False)
    print("[*] Dataset created: dga_dataset.csv (1000 samples)")

if __name__ == "__main__":
    create_dataset()
