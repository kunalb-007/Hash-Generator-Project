import hashlib
import argparse
import os

def generate_hash(input_data, algorithm):
  # Generate the hash using the specified algorithm
  if algorithm == "md5":
    hash_value = hashlib.md5(input_data.encode()).hexdigest()
  elif algorithm == "sha1":
    hash_value = hashlib.sha1(input_data.encode()).hexdigest()
  elif algorithm == "sha256":
    hash_value = hashlib.sha256(input_data.encode()).hexdigest()
  elif algorithm == "sha512":
    hash_value = hashlib.sha512(input_data.encode()).hexdigest()
  else:
    print("Error: Unsupported algorithm")
    return
  return hash_value

def generate_file_hash(file_path, algorithm):
  # Open the file and read its contents
  with open(file_path, "rb") as f:
    file_data = f.read()
  # Generate the hash using the specified algorithm
  hash_value = generate_hash(file_data, algorithm)
  return hash_value

def main():
  # Parse command-line arguments
  parser = argparse.ArgumentParser(description="Hash generation tool")
  parser.add_argument("-d", "--data", help="Data to be hashed")
  parser.add_argument("-f", "--file", help="File to be hashed")
  parser.add_argument("-a", "--algorithm", help="Hash algorithm to use (md5, sha1, sha256, sha512)", default="sha256")
  args = parser.parse_args()
  
  # Check if data or file was specified
  if args.data:
    # Generate hash for the specified data
    hash_value = generate_hash(args.data, args.algorithm)
    print("The hash value is:", hash_value)
  elif args.file:
    # Check if the specified file exists
    if not os.path.isfile(args.file):
      print("Error: File does not exist")
      return
    # Generate hash for the specified file
    hash_value = generate_file_hash(args.file, args.algorithm)
    print("The hash value for file '{}' is: {}".format(args.file, hash_value))
  else:
    # Display usage information if no data or file was specified
    parser.print_help()

if __name__ == "__main__":
  main()