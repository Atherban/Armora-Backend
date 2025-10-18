// services/aiChat.service.js
import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv";

dotenv.config();
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

export const chatWithAI = async (analysisData, userMessage) => {
  const prompt = `
You are a cybersecurity assistant AI.
The following system analysis has already been completed:

${JSON.stringify(analysisData, null, 2)}

Now, the user is asking this follow-up question:
"${userMessage}"

Respond conversationally but factually. Use 2–4 sentences.
Stay grounded in the provided analysis context.
If user asks about how to improve something, give actionable advice.
`;

  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    const result = await model.generateContent(prompt);
    const text = result.response.text();

    return { reply: text };
  } catch (error) {
    console.error("Chat AI error:", error.message);
    return {
      reply:
        "Sorry, I couldn’t process your question right now. Please try again in a moment.",
    };
  }
};
