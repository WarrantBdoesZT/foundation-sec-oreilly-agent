"""
Standalone smoke test: confirms the O'Reilly MCP tool, Ollama models, and
RAG store are all reachable BEFORE you wire anything into Open WebUI.

Run this first on a fresh setup. If it works here, the full HTTP service
(agent_server.py) will too -- any later failure is then a wiring/networking
issue, not a logic issue.

Usage:
    OREILLY_TOKEN="your-token" python test_agent.py
"""
import asyncio
import os
from langchain_ollama import ChatOllama
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

OREILLY_TOKEN = os.environ["OREILLY_TOKEN"]
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
ORCH_MODEL = os.environ.get("ORCH_MODEL", "llama3.2:3b")


async def main():
    print(f"Connecting to Ollama at {OLLAMA_BASE_URL}, model={ORCH_MODEL} ...")
    llm = ChatOllama(base_url=OLLAMA_BASE_URL, model=ORCH_MODEL, temperature=0)

    print("Connecting to O'Reilly MCP server ...")
    client = MultiServerMCPClient({
        "oreilly": {
            "transport": "streamable_http",
            "url": "https://api.oreilly.com/api/content-discovery/v1/mcp/",
            "headers": {"Authorization": f"Bearer {OREILLY_TOKEN}"},
        }
    })
    tools = await client.get_tools()
    print("Loaded tools:", [t.name for t in tools])

    agent = create_react_agent(llm, tools)
    result = await agent.ainvoke({
        "messages": "Search O'Reilly for books on Kubernetes security and summarize the top result."
    })
    print("\n--- Agent response ---\n")
    print(result["messages"][-1].content)

    print("\n--- Checking RAG store ---")
    try:
        from rag_tools import _get_collection
        count = _get_collection().count()
        print(f"Local RAG store has {count} chunk(s). "
              f"{'(Empty is fine on a fresh install -- run ingest_docs.py to add content.)' if count == 0 else ''}")
    except Exception as e:
        print(f"Could not check RAG store: {e}")


if __name__ == "__main__":
    asyncio.run(main())
