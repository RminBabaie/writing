filename="dogs.txt"
filename1="cats.txt"
try: 
    with open(filename,encoding="utf-8") as Dogs , open(filename1,encoding="utf-8") as Cats:
        dogs=Dogs.read()
        cats=Cats.read()
    print(f"{dogs}\n{cats}")
except FileNotFoundError:
    pass
