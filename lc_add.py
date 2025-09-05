from curses.ascii import isalpha

flag=True

while flag:
    print("(1) Encrypt")
    print("(2) Decrypt")
    print("Enter your choice: ")
    choice=int(input())

    if choice==1:
        print("Enter plaintext: ")
        p=input()
        print("Enter key: ")
        k=int(input())
        c=[]
        for i in p:
            if i==' ':
                c.append(' ')
                continue
            if i.islower():
                c.append(chr((ord(i) + k -ord('a')) % 26 + ord('a')))
                continue
            if i.isupper():
                c.append(chr((ord(i) + k - ord('A')) % 26 + ord('A')))
                continue
            if i.isnumeric():
                c.append(chr((ord(i) + k - ord('0')) % 10 + ord('0')))
                continue
            else:
                c.append(i)
                continue
        print("Cipher text is: ", "".join(c))
        for i in p:
            if i==' ':
                c.append(' ')
                continue
            if i.islower():
                c.append(chr((ord(i)*k -ord('a')) % 26 + ord('a')))
                continue
            if i.isupper():
                c.append(chr((ord(i)*k - ord('A')) % 26 + ord('A')))
                continue
            if i.isnumeric():
                c.append(chr((ord(i)*k - ord('0')) % 10 + ord('0')))
                continue
            else:
                c.append(i)
                continue
        c=[]
        print("Multiplicative cipher text is: ", "".join(c))


    elif choice==2:
        print("Enter cipher text: ")
        c = input()
        print("Enter key: ")
        k = int(input())
        p = []
        for i in c:
            if i==' ':
                p.append(' ')
                continue
            if i.islower():
                p.append(chr((ord(i) - k - ord('a')) % 26 + ord('a')))
                continue
            if i.isupper():
                p.append(chr((ord(i) - k - ord('A')) % 26 + ord('A')))
                continue
            if i.isnumeric():
                p.append(chr((ord(i) - k - ord('0')) % 10 + ord('0')))
                continue
            else:
                p.append(i)
        print("Plaintext is: ", "".join(p))

    else:
        print("Invalid input")

    print("Do you want to continue? (3)")
    choice=int(input())
    if choice!=3:
        flag=False
