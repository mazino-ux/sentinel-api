const { randomBytes } = require("crypto");

const logAndRespond = (res, error) => { //this function logs the error and sends a response to the client
  const errorId = randomBytes(4).toString("hex"); //this generates a random error ID for tracking
  console.error(`[${errorId}]`, error);
  return res.status(500).json({
    success: false,
    message: `Internal error. Reference: ${errorId}`,
  });
};

// export default { logAndRespond };
module.exports = logAndRespond; // Exporting the error handler function for use in other parts of the application
