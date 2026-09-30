"""Pipeline orchestration (fetch -> rules -> gate -> redact -> classify -> store).

Built out in phases 2 and 3. Depends only on interfaces, never on concrete
providers, stores or delivery channels.
"""
