#!/bin/bash

# Create project directories
mkdir -p data/rules
mkdir -p models
mkdir -p static/css
mkdir -p static/js
mkdir -p static/sounds
mkdir -p templates
mkdir -p logs

# Verify directory structure
echo "Verifying project structure..."
for dir in data/rules models static/css static/js static/sounds templates logs; do
    if [ -d "$dir" ]; then
        echo "✓ $dir directory exists"
    else
        echo "✗ Failed to create $dir directory"
        exit 1
    fi
done

echo "Project structure setup complete!"
