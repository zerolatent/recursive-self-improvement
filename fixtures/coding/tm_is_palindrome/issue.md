# Bug: "A man a plan a canal Panama" is reported as not a palindrome

`is_palindrome` compares the raw string to its reverse without normalizing case, spaces, or punctuation first.
