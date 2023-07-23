import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import { terser } from "rollup-plugin-minification";

export default {
    input: "src/main.ts",
    output: [
        {
            file: "build/js-encryption.js",
            name: "js_encryption",
            format: "umd",
        },
        {
            file: "build/js-encryption.esm.js",
            format: "es",
        },
    ],
    plugins: [
        typescript(),
        terser({
            output: { comments: false },
        }),
        nodeResolve(),
    ],
};