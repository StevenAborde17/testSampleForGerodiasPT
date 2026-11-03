const supabase = require("./src/config/supabaseClient");

async function verifyConnection() {
  console.log("Checking connection...");
  const { error } = await supabase.from("test").select("*").limit(1);

  if (!error || error.code === "PGRST205") {
    console.log("Supabase connection OK");
  } else {
    console.error("Connection failed:", error.message);
    process.exit(1);
  }
}

verifyConnection();
