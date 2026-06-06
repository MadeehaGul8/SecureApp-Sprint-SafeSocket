import js from "@eslint/js";
import security from "eslint-plugin-security";

export default [
    js.configs.recommended,
    security.configs.recommended,
    {
        rules: {
            "security/detect-non-literal-fs-filename": "warn",
            "security/detect-object-injection": "warn",
            "security/detect-possible-timing-attacks": "warn"
        }
    }
];