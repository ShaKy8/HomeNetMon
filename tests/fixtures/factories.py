"""
Smart factory imports that fallback to simple implementations if dependencies are missing.

This module tries to import factory_boy based factories first, and falls back
to simple built-in factories if the dependencies are not available.
"""

try:
    # Try to import factory_boy based factories
    import factory
    import factory.fuzzy
    from faker import Faker
    
    # If successful, import from the original factories
    from .factories_original import *
    
except ImportError:
    # Fall back to simple factories if factory_boy is not available
    import warnings
    warnings.warn(
        "factory_boy or faker not available. Using simple fallback factories. "
        "For full testing capabilities, install: pip install factory-boy faker",
        ImportWarning
    )
    
    from .simple_factories import *