# SLM Chatbot

This repository contains a Flask-based business analytics chatbot that turns plain-language questions into role-aware MySQL queries and returns the source rows used for each answer.

The application lives in [`rag_chatbot/`](rag_chatbot/). Start with its [setup and security notes](rag_chatbot/README.md).

Key capabilities include revocable server-side sessions, region and department row scopes, field-level access rules, parsed read-only SQL validation, bounded results, query auditing, bounded conversation memory for follow-up questions, a responsive analytics workspace, and shared model capacity limits for concurrent users.
