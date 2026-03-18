## 🛡️ Top 5 Security Rules for OpenClaw Users

Protecting your AI agent isn't just about code; it's about how you set it up and use it. If you're not deeply technical, follow these 5 golden rules to keep your agent (and your wallet) safe:

### 1. Choose a "Hardened" AI Model
Not all AI models are created equal when it comes to resisting hacks (like "Prompt Injection," where attackers trick the AI into ignoring your rules). 
*   **Recommendation:** Use established, highly secure models for your main agent, such as **Google Gemini 2.5/3.0+** or **OpenAI GPT-4o**.
*   **Why?** These providers invest millions in "red-teaming" (testing their own models against attacks). Smaller, open-source, or unverified models are much easier to manipulate into giving up your secrets.

### 2. Never Share Your Agent Publicly
Your agent costs money (API tokens) and has access to your private workspace.
*   **Recommendation:** In your OpenClaw settings (`openclaw.json`), ensure your Telegram or Signal `dmPolicy` and `groupPolicy` are set to `allowlist`.
*   **Why?** If set to `public`, anyone on the internet can chat with your bot, run up a massive API bill, or try to trick it into deleting your files. Only add your own User ID to the allowlist.

### 3. Treat Your Prompt Like a Password
The instructions you give your agent (your `SOUL.md` or System Prompt) often contain sensitive logic about how your business works.
*   **Recommendation:** Never instruct your AI to "share your system prompt" with users.
*   **Why?** Attackers use a technique called "System Prompt Extraction." If they know exactly how your AI is instructed, they can find loopholes to break it.

### 4. Isolate the File System (Sandboxing)
*   **Recommendation:** Always ensure the **Sandbox** is turned `on` and `workspaceOnly` is set to `true`. Our toolkit does this for you automatically!
*   **Why?** If the AI goes rogue (or is tricked), sandboxing acts as a digital cage. It prevents the AI from reaching out and deleting your server's core operating system files.

### 5. Don't Hardcode API Keys
*   **Recommendation:** Never type your `sk-1234...` API keys directly into text files or your prompt. Use environment variables or a secure secret manager (like our `vault.sh` integration).
*   **Why?** If you accidentally share a screenshot, or if the AI accidentally quotes a file, your keys can be stolen and used by others within minutes.
