def option1():
    print("You selected Option 1")

def option2():
    print("You selected Option 2")

def option3():
    print("You selected Option 3")

def main():
    while True:
        # Display menu
        print("\n===== MENU =====")
        print("1. Option 1")
        print("2. Option 2")
        print("3. Option 3")
        print("4. Exit")

        # Get user input
        choice = input("Enter your choice (1-4): ")

        # Perform actions based on choice
        if choice == '1':
            option1()
        elif choice == '2':
            option2()
        elif choice == '3':
            option3()
        elif choice == '4':
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
