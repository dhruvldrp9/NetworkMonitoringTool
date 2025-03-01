#!/usr/bin/env python3
import toml
import os

def generate_requirements():
    """Generate requirements.txt from pyproject.toml"""
    try:
        # Read pyproject.toml
        with open('pyproject.toml', 'r') as f:
            config = toml.load(f)
        
        # Extract dependencies
        dependencies = config['project']['dependencies']
        
        # Write requirements.txt
        with open('requirements.txt', 'w') as f:
            for dep in dependencies:
                # Clean up the dependency string
                dep = dep.replace('>=', '==')
                f.write(f"{dep}\n")
            
            # Add additional required packages not in pyproject.toml
            f.write("python-dotenv==1.0.0\n")  # For environment variables
        
        print("Successfully generated requirements.txt")
    except Exception as e:
        print(f"Error generating requirements.txt: {e}")

if __name__ == "__main__":
    generate_requirements()
