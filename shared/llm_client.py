from shared.config import config

def get_llm(temperature: float = 0, streaming: bool = False):
    if config.LLM_PROVIDER == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=config.LLM_MODEL,
            groq_api_key=config.GROQ_API_KEY,
            temperature=temperature,
        )
    elif config.LLM_PROVIDER == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=config.LLM_MODEL,
            temperature=temperature,
        )
    elif config.LLM_PROVIDER == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=config.LLM_MODEL,
            google_api_key=config.GOOGLE_API_KEY,
            temperature=temperature,
        )
    elif config.LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=config.LLM_MODEL,
            anthropic_api_key=config.ANTHROPIC_API_KEY,
            temperature=temperature,
            streaming=streaming,
        )
    else:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=config.LLM_MODEL,
            openai_api_key=config.OPENAI_API_KEY,
            temperature=temperature,
            streaming=streaming,
        )

def get_llm_with_tools(tools: list, temperature: float = 0):
    llm = get_llm(temperature=temperature)
    return llm.bind_tools(tools)
