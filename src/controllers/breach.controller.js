import { getBreachData, breachService } from "../services/breach.service.js";
import { generateRecommendations } from "../utils/recommedations.js";

// Response Formatters
const formatErrorResponse = (message, statusCode = 400) => ({
  success: false,
  message,
  timestamp: new Date().toISOString(),
});

const formatSuccessResponse = (breachResult, recommendations) => ({
  success: true,
  summary: breachResult.summary,
  breaches: breachResult.breaches,
  recommendations,
  query: breachResult.query,
  timestamp: breachResult.timestamp,
});

// Validation Functions
const validateRequest = (query) => {
  if (!query || query.trim() === "") {
    return { isValid: false, error: "Email or username is required." };
  }

  if (typeof query !== "string") {
    return { isValid: false, error: "Query must be a string." };
  }

  return { isValid: true };
};

// Statistics Calculator
const calculateBreachStatistics = (breaches) => {
  if (!breaches || breaches.length === 0) {
    return {
      totalBreaches: 0,
      criticalIssues: 0,
      dataTypes: 0,
      lastBreach: null,
      severityBreakdown: {
        high: 0,
        medium: 0,
        low: 0,
      },
    };
  }

  const criticalIssues = breaches.filter(
    (breach) => breach.severity === "high"
  ).length;

  const severityBreakdown = breaches.reduce(
    (acc, breach) => {
      acc[breach.severity] = (acc[breach.severity] || 0) + 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0 }
  );

  // Sort breaches by date to find the most recent
  const sortedBreaches = [...breaches].sort((a, b) => {
    // This would need actual date comparison if dates were available
    return 0; // Placeholder - implement based on your data structure
  });

  return {
    totalBreaches: breaches.length,
    criticalIssues,
    dataTypes: breaches.reduce((acc, breach) => {
      // Count different types of compromised data
      const types = new Set();
      if (breach.email && breach.email !== "Unknown") types.add("email");
      if (breach.passwordMasked && breach.passwordMasked !== "****")
        types.add("password");
      if (breach.hash) types.add("hash");
      if (breach.sha1) types.add("sha1");
      return acc + types.size;
    }, 0),
    lastBreach: sortedBreaches[0]?.source || "Unknown",
    severityBreakdown,
  };
};

// Service Health Check
const checkServiceHealth = () => {
  const status = breachService.getStatus();
  if (!status.configured) {
    return {
      healthy: false,
      message: "Breach service is not properly configured.",
    };
  }
  return { healthy: true };
};

// Main Controller
export const handleDataBreachCheck = async (req, res) => {
  const { query } = req.body;

  // Validate request
  const validation = validateRequest(query);
  if (!validation.isValid) {
    return res.status(400).json(formatErrorResponse(validation.error));
  }

  // Check service health
  const healthCheck = checkServiceHealth();
  if (!healthCheck.healthy) {
    return res.status(503).json(formatErrorResponse(healthCheck.message, 503));
  }

  try {
    // Get breach data from service
    const breachResult = await getBreachData(query.trim());

    // Handle service-level errors
    if (!breachResult.success) {
      return res.status(422).json({
        success: false,
        message: breachResult.summary,
        error: breachResult.error,
        query: breachResult.query,
        timestamp: breachResult.timestamp,
      });
    }

    // Calculate statistics
    const statistics = calculateBreachStatistics(breachResult.breaches);

    // Generate recommendations
    const recommendations = generateRecommendations(breachResult.breaches);

    // Prepare final response
    const response = {
      ...formatSuccessResponse(breachResult, recommendations),
      summary: {
        ...statistics,
        query: breachResult.query,
        found: breachResult.found,
      },
    };

    // Log successful query (without sensitive data)
    console.log(
      `✅ Breach check completed for: ${query} - Found: ${breachResult.found} breaches`
    );

    return res.json(response);
  } catch (error) {
    console.error("❌ Data Breach Controller Error:", {
      query,
      error: error.message,
      stack: error.stack,
    });

    // Determine appropriate status code
    const statusCode = error.response?.status || 500;
    const errorMessage =
      statusCode === 500
        ? "Failed to check data breaches. Please try again later."
        : error.message;

    return res
      .status(statusCode)
      .json(formatErrorResponse(errorMessage, statusCode));
  }
};

// Additional Controller Methods
export const breachController = {
  // Main breach check handler
  checkBreaches: handleDataBreachCheck,

  // Service status endpoint
  getServiceStatus: async (req, res) => {
    try {
      const status = breachService.getStatus();

      return res.json({
        success: true,
        service: "Data Breach Check",
        status: status.configured ? "operational" : "misconfigured",
        configured: status.configured,
        apiHost: status.apiHost,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("❌ Service Status Check Error:", error.message);
      return res
        .status(500)
        .json(formatErrorResponse("Failed to check service status", 500));
    }
  },

  // Batch check endpoint
  batchCheckBreaches: async (req, res) => {
    const { queries } = req.body;

    if (!queries || !Array.isArray(queries)) {
      return res
        .status(400)
        .json(formatErrorResponse("Queries must be provided as an array"));
    }

    if (queries.length > 10) {
      return res
        .status(400)
        .json(
          formatErrorResponse("Maximum 10 queries allowed per batch request")
        );
    }

    try {
      const results = [];

      for (const query of queries) {
        const validation = validateRequest(query);
        if (!validation.isValid) {
          results.push({
            success: false,
            query,
            error: validation.error,
            timestamp: new Date().toISOString(),
          });
          continue;
        }

        try {
          const breachResult = await getBreachData(query.trim());
          const statistics = calculateBreachStatistics(breachResult.breaches);
          const recommendations = generateRecommendations(
            breachResult.breaches
          );

          results.push({
            success: breachResult.success,
            query,
            summary: statistics,
            breaches: breachResult.breaches,
            recommendations,
            timestamp: breachResult.timestamp,
          });
        } catch (error) {
          results.push({
            success: false,
            query,
            error: error.message,
            timestamp: new Date().toISOString(),
          });
        }
      }

      console.log(
        `✅ Batch breach check completed: ${queries.length} queries processed`
      );

      return res.json({
        success: true,
        totalQueries: queries.length,
        processed: results.length,
        results,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("❌ Batch Breach Check Error:", error.message);
      return res
        .status(500)
        .json(formatErrorResponse("Failed to process batch request", 500));
    }
  },
};

// Export individual functions for testing
export const __testing__ = {
  validateRequest,
  calculateBreachStatistics,
  checkServiceHealth,
  formatErrorResponse,
  formatSuccessResponse,
};
