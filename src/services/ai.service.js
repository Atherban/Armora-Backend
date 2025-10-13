// services/ai.service.js
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

/**
 * Analyzes a URL for security threats and returns comprehensive security assessment
 * @param {string} url - The URL to analyze
 * @returns {Promise<Object>} Complete security analysis result
 */

async function analyzeURL(url) {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: `Analyze this URL for security threats and return ONLY JSON: ${url}
      
      You are a cybersecurity expert. Analyze the URL thoroughly and return a JSON object with this exact structure:
      {
        "isMalicious": boolean,
        "confidence": number between 0-1,
        "riskLevel": "LOW", "MEDIUM", "HIGH", or "CRITICAL",
        "threats": array of strings describing specific threats found,
        "reasons": array of strings explaining why it's malicious/safe,
        "recommendations": array of strings with safety advice,
        "categories": array of threat categories like ["phishing", "malware", "scam"],
        "domainAnalysis": object with {isSuspicious: boolean, details: string},
        "contentAnalysis": object with {riskScore: number, details: string},
        "technicalAnalysis": object with {issues: array, details: string}
      }

      Check for:
      - Phishing attempts and fake login pages
      - Malware distribution signs
      - Suspicious domain patterns (typosquatting, weird TLDs)
      - URL structure anomalies
      - Social engineering patterns
      - Security protocol issues
      - Known malicious patterns
      - Suspicious subdomains or paths

      Be specific and detailed in your analysis.`,
      generationConfig: {
        temperature: 0.1,
        maxOutputTokens: 2048,
      },
    });

    return parseResponse(response.text, url);
  } catch (error) {
    console.error("URL Analysis Error:", error);
    return getErrorAnalysis(url);
  }
}

function parseResponse(responseText, url) {
  try {
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON found");

    const analysis = JSON.parse(jsonMatch[0]);

    return {
      // Core assessment
      isMalicious: Boolean(analysis.isMalicious),
      confidence: Math.max(0, Math.min(1, analysis.confidence || 0.5)),
      riskLevel: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(
        analysis.riskLevel
      )
        ? analysis.riskLevel
        : "MEDIUM",

      // Threat details
      threats: Array.isArray(analysis.threats) ? analysis.threats : [],
      reasons: Array.isArray(analysis.reasons) ? analysis.reasons : [],
      recommendations: Array.isArray(analysis.recommendations)
        ? analysis.recommendations
        : [],
      categories: Array.isArray(analysis.categories) ? analysis.categories : [],

      // Detailed analysis sections
      domainAnalysis: analysis.domainAnalysis || {
        isSuspicious: false,
        details: "No domain analysis available",
      },
      contentAnalysis: analysis.contentAnalysis || {
        riskScore: 0.5,
        details: "No content analysis available",
      },
      technicalAnalysis: analysis.technicalAnalysis || {
        issues: [],
        details: "No technical analysis available",
      },

      // Metadata
      analyzedUrl: url,
      timestamp: new Date().toISOString(),
      safe: !analysis.isMalicious,
    };
  } catch (error) {
    console.error("Parse error:", error);
    return getErrorAnalysis(url);
  }
}

function getErrorAnalysis(url) {
  return {
    isMalicious: false,
    confidence: 0.3,
    riskLevel: "MEDIUM",
    threats: ["Analysis service temporarily unavailable"],
    reasons: ["Could not complete security scan"],
    recommendations: ["Proceed with caution", "Verify URL through other means"],
    categories: ["analysis_error"],
    domainAnalysis: { isSuspicious: false, details: "Analysis failed" },
    contentAnalysis: { riskScore: 0.5, details: "Analysis failed" },
    technicalAnalysis: { issues: [], details: "Analysis failed" },
    analyzedUrl: url,
    timestamp: new Date().toISOString(),
    safe: false,
    error: true,
  };
}

export default { analyzeURL };
