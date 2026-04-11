#!/usr/bin/env python3
"""Analyze diff output for common issues."""

import sys

def analyze(diff_text):
    issues = []
    for i, line in enumerate(diff_text.splitlines()):
        if "TODO" in line:
            issues.append(f"Line {i}: TODO found")
    return issues

if __name__ == "__main__":
    print("\n".join(analyze(sys.stdin.read())))
