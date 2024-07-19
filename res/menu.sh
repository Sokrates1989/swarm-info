#!/bin/bash

# Menu options.
show_menu_options() {
    echo "1) Option 1"
    echo "2) Option 2"
    echo "3) Option 3"
    echo "q) Quit"
}


# Function to display the menu.
show_menu() {
    # Main loop
    while true; do
        show_menu_options
        read -n 1 -p "Please select an option: " choice
        echo    # Move to a new line after reading input

        case $choice in
            1)
                option1
                ;;
            2)
                option2
                ;;
            3)
                option3
                ;;
            q)
                echo "Thanks for using swarm-info!"
                echo "Have a great day :)"
                break
                ;;
            *)
                echo "Invalid option, please try again."
                ;;
        esac
    done
}

# Function to handle Option 1
option1() {
    echo "You selected Option 1"
    # Add your code for Option 1 here
}

# Function to handle Option 2
option2() {
    echo "You selected Option 2"
    # Add your code for Option 2 here
}

# Function to handle Option 3
option3() {
    echo "You selected Option 3"
    # Add your code for Option 3 here
}

# Actually menu with options.
show_menu