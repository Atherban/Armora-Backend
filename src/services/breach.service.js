import axios from "axios";

// Constants and Configuration
const CONFIG = {
  RAPIDAPI_KEY: process.env.BREACH_API_KEY,
  RAPIDAPI_HOST: process.env.RAPIDAPI_HOST || "breachdirectory.p.rapidapi.com",
  BREACH_API_URL: `https://${
    process.env.RAPIDAPI_HOST || "breachdirectory.p.rapidapi.com"
  }/`,
  REQUEST_TIMEOUT: 10000, // 10 seconds
};

// Utility Functions
const maskPassword = (password) => {
  if (!password) return "";
  if (password.length <= 4) return "****";
  return `${password.slice(0, 2)}***${password.slice(-2)}`;
};

const determineSeverity = (breach) => {
  if (breach.hash_password) return "medium";
  if (breach.password && breach.password.length > 0) return "high";
  return "low";
};

const generateSummary = (breach, index) => {
  const source = breach.sources || "Unknown";
  const passwordType = breach.hash_password ? "hashed" : "plaintext";
  return `Breach #${index + 1}: Email ${
    breach.email || "Unknown"
  } exposed in ${source}. Password is ${passwordType}.`;
};

// Data Processing Functions
const processBreachRecord = (record, index) => ({
  email: record.email || "Unknown",
  passwordMasked: maskPassword(record.password),
  hashType: record.hash_password ? "Hashed" : "Plaintext",
  sha1: record.sha1 || null,
  hash: record.hash || null,
  source: record.sources || "Unknown",
  summary: generateSummary(record, index),
  severity: determineSeverity(record),
});

const validateApiResponse = (data) => {
  return data && typeof data === "object";
};

const validateQuery = (query) => {
  if (!query || query.trim().length === 0) {
    return { isValid: false, error: "Query cannot be empty" };
  }

  if (query.length > 254) {
    return { isValid: false, error: "Query too long" };
  }

  // Basic email validation if query looks like an email
  if (query.includes("@")) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(query)) {
      return { isValid: false, error: "Invalid email format" };
    }
  }

  return { isValid: true };
};

// API Client
class BreachApiClient {
  constructor() {
    this.baseURL = CONFIG.BREACH_API_URL;
    this.headers = {
      "x-rapidapi-key": CONFIG.RAPIDAPI_KEY || "",
      "x-rapidapi-host": CONFIG.RAPIDAPI_HOST,
    };
  }

  validateConfig() {
    if (!CONFIG.RAPIDAPI_KEY) {
      throw new Error(
        "Missing RapidAPI key. Please check your environment variables."
      );
    }
  }

  async makeRequest(query) {
    this.validateConfig();

    const options = {
      method: "GET",
      url: this.baseURL,
      params: {
        func: "auto",
        term: query.trim(),
      },
      headers: this.headers,
      timeout: CONFIG.REQUEST_TIMEOUT,
    };

    return await axios.request(options);
  }
}

// Error Handler
const handleApiError = (error) => {
  let errorMessage = "Unknown API error";
  let summary = "Service temporarily unavailable";

  if (error.response) {
    // API responded with error status
    const status = error.response.status;

    switch (status) {
      case 400:
        errorMessage = "Bad request - invalid query parameters";
        summary = "Invalid search query";
        break;
      case 401:
        errorMessage = "Unauthorized - invalid API key";
        summary = "API authentication failed";
        break;
      case 403:
        errorMessage = "Forbidden - access denied";
        summary = "Access to breach data denied";
        break;
      case 404:
        errorMessage = "Not found - API endpoint unavailable";
        summary = "Service endpoint not found";
        break;
      case 429:
        errorMessage = "Too many requests - rate limit exceeded";
        summary = "Rate limit exceeded, please try again later";
        break;
      case 500:
        errorMessage = "Internal server error";
        summary = "Breach service temporarily unavailable";
        break;
      default:
        errorMessage = `API error: ${status}`;
        summary = "Service error occurred";
    }
  } else if (error.request) {
    // Network error
    errorMessage = "Network error - unable to reach breach service";
    summary = "Network connection failed";
  } else {
    // Other errors
    errorMessage = error.message || "Unknown error occurred";
    summary = "Unexpected error occurred";
  }

  return { errorMessage, summary };
};

// Response Formatter
const formatSuccessResponse = (data, query, breaches) => {
  const foundCount = data.found || breaches.length;
  const success = Boolean(data.success) && foundCount > 0;

  return {
    success,
    found: foundCount,
    breaches,
    summary: success
      ? `Found ${foundCount} breach${
          foundCount !== 1 ? "es" : ""
        } for "${query}"`
      : `No breaches found for "${query}"`,
    query,
    timestamp: new Date().toISOString(),
  };
};

const formatErrorResponse = (error, query, customSummary = null) => {
  const { errorMessage, summary } = handleApiError(error);

  return {
    success: false,
    found: 0,
    breaches: [],
    summary: customSummary || summary,
    error: errorMessage,
    query,
    timestamp: new Date().toISOString(),
  };
};

// Main Service Function
export const getBreachData = async (query) => {
  const timestamp = new Date().toISOString();

  // Input validation
  const validation = validateQuery(query);
  if (!validation.isValid) {
    return {
      success: false,
      found: 0,
      breaches: [],
      summary: validation.error || "Invalid query",
      error: validation.error,
      query,
      timestamp,
    };
  }

  // Configuration validation
  if (!CONFIG.RAPIDAPI_KEY) {
    const errorMsg = "Missing RapidAPI key configuration";
    console.error("❌ Breach Service Error:", errorMsg);
    return {
      success: false,
      found: 0,
      breaches: [],
      summary: "Service configuration error",
      error: errorMsg,
      query,
      timestamp,
    };
  }

  try {
    const apiClient = new BreachApiClient();
    const response = await apiClient.makeRequest(query);
    const data = response.data;

    // Validate response structure
    if (!validateApiResponse(data)) {
      return formatErrorResponse(
        new Error("Invalid API response format"),
        query,
        "Invalid API response format"
      );
    }

    // Process breach data
    const breaches = Array.isArray(data.result)
      ? data.result.map(processBreachRecord)
      : [];

    return formatSuccessResponse(data, query, breaches);
  } catch (error) {
    console.error("❌ Breach Service Error:", {
      query,
      error: error.message,
      status: error.response?.status,
      timestamp,
    });

    return formatErrorResponse(error, query);
  }
};

// Additional utility functions for enhanced functionality
export const breachService = {
  // Check if service is configured properly
  isConfigured: () => {
    return !!CONFIG.RAPIDAPI_KEY;
  },

  // Get service status
  getStatus: () => {
    return {
      configured: !!CONFIG.RAPIDAPI_KEY,
      apiHost: CONFIG.RAPIDAPI_HOST,
      timeout: CONFIG.REQUEST_TIMEOUT,
    };
  },

  // Batch query multiple emails (placeholder for future enhancement)
  batchQuery: async (queries) => {
    if (!Array.isArray(queries)) {
      throw new Error("Queries must be an array");
    }

    const results = [];
    for (const query of queries) {
      try {
        const result = await getBreachData(query);
        results.push(result);
      } catch (error) {
        results.push({
          success: false,
          found: 0,
          breaches: [],
          summary: `Failed to query: ${query}`,
          error: error.message,
          query,
          timestamp: new Date().toISOString(),
        });
      }
    }

    return results;
  },
};

// Export utilities for testing
export const breachUtils = {
  maskPassword,
  determineSeverity,
  generateSummary,
  processBreachRecord,
  validateQuery,
  validateApiResponse,
  handleApiError,
};
