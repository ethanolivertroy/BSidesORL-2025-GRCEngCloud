#!/usr/bin/env python3
"""Compatibility wrapper for the maintained HTML report generator."""

try:
    from .report_generator_simple import generate_html_report
except ImportError:
    from report_generator_simple import generate_html_report


__all__ = ["generate_html_report"]
