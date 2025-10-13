import mongoose from "mongoose";

export const connectDB = async () => {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("Database connected Successfully"))
    .catch((err) => console.log("Error Connecting to DB : ", err));
};
