import json
filename="username.json"
username=input("please enter your user name==>")
with open(filename,"w") as f:
    json.dump(username,f)
print("thank you , we will remeber this next time")