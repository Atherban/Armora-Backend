import app from "./src/app.js";
import "dotenv/config";
import { connectDB } from "./src/db/db.js";

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  connectDB();
});
