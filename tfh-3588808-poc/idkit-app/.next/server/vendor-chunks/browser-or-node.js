"use strict";
/*
 * ATTENTION: An "eval-source-map" devtool has been used.
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file with attached SourceMaps in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
exports.id = "vendor-chunks/browser-or-node";
exports.ids = ["vendor-chunks/browser-or-node"];
exports.modules = {

/***/ "(ssr)/./node_modules/browser-or-node/dist/index.mjs":
/*!*****************************************************!*\
  !*** ./node_modules/browser-or-node/dist/index.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   isBrowser: () => (/* binding */ isBrowser),\n/* harmony export */   isDeno: () => (/* binding */ isDeno),\n/* harmony export */   isJsDom: () => (/* binding */ isJsDom),\n/* harmony export */   isNode: () => (/* binding */ isNode),\n/* harmony export */   isWebWorker: () => (/* binding */ isWebWorker)\n/* harmony export */ });\n// src/index.ts\nvar isBrowser = typeof window !== \"undefined\" && typeof window.document !== \"undefined\";\nvar isNode = (\n  // @ts-expect-error\n  typeof process !== \"undefined\" && // @ts-expect-error\n  process.versions != null && // @ts-expect-error\n  process.versions.node != null\n);\nvar isWebWorker = typeof self === \"object\" && self.constructor && self.constructor.name === \"DedicatedWorkerGlobalScope\";\nvar isJsDom = typeof window !== \"undefined\" && window.name === \"nodejs\" || typeof navigator !== \"undefined\" && \"userAgent\" in navigator && typeof navigator.userAgent === \"string\" && (navigator.userAgent.includes(\"Node.js\") || navigator.userAgent.includes(\"jsdom\"));\nvar isDeno = (\n  // @ts-expect-error\n  typeof Deno !== \"undefined\" && // @ts-expect-error\n  typeof Deno.version !== \"undefined\" && // @ts-expect-error\n  typeof Deno.version.deno !== \"undefined\"\n);\n\n//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiKHNzcikvLi9ub2RlX21vZHVsZXMvYnJvd3Nlci1vci1ub2RlL2Rpc3QvaW5kZXgubWpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFPRSIsInNvdXJjZXMiOlsid2VicGFjazovL2lka2l0LWFwcC8uL25vZGVfbW9kdWxlcy9icm93c2VyLW9yLW5vZGUvZGlzdC9pbmRleC5tanM/YzRmMyJdLCJzb3VyY2VzQ29udGVudCI6WyIvLyBzcmMvaW5kZXgudHNcbnZhciBpc0Jyb3dzZXIgPSB0eXBlb2Ygd2luZG93ICE9PSBcInVuZGVmaW5lZFwiICYmIHR5cGVvZiB3aW5kb3cuZG9jdW1lbnQgIT09IFwidW5kZWZpbmVkXCI7XG52YXIgaXNOb2RlID0gKFxuICAvLyBAdHMtZXhwZWN0LWVycm9yXG4gIHR5cGVvZiBwcm9jZXNzICE9PSBcInVuZGVmaW5lZFwiICYmIC8vIEB0cy1leHBlY3QtZXJyb3JcbiAgcHJvY2Vzcy52ZXJzaW9ucyAhPSBudWxsICYmIC8vIEB0cy1leHBlY3QtZXJyb3JcbiAgcHJvY2Vzcy52ZXJzaW9ucy5ub2RlICE9IG51bGxcbik7XG52YXIgaXNXZWJXb3JrZXIgPSB0eXBlb2Ygc2VsZiA9PT0gXCJvYmplY3RcIiAmJiBzZWxmLmNvbnN0cnVjdG9yICYmIHNlbGYuY29uc3RydWN0b3IubmFtZSA9PT0gXCJEZWRpY2F0ZWRXb3JrZXJHbG9iYWxTY29wZVwiO1xudmFyIGlzSnNEb20gPSB0eXBlb2Ygd2luZG93ICE9PSBcInVuZGVmaW5lZFwiICYmIHdpbmRvdy5uYW1lID09PSBcIm5vZGVqc1wiIHx8IHR5cGVvZiBuYXZpZ2F0b3IgIT09IFwidW5kZWZpbmVkXCIgJiYgXCJ1c2VyQWdlbnRcIiBpbiBuYXZpZ2F0b3IgJiYgdHlwZW9mIG5hdmlnYXRvci51c2VyQWdlbnQgPT09IFwic3RyaW5nXCIgJiYgKG5hdmlnYXRvci51c2VyQWdlbnQuaW5jbHVkZXMoXCJOb2RlLmpzXCIpIHx8IG5hdmlnYXRvci51c2VyQWdlbnQuaW5jbHVkZXMoXCJqc2RvbVwiKSk7XG52YXIgaXNEZW5vID0gKFxuICAvLyBAdHMtZXhwZWN0LWVycm9yXG4gIHR5cGVvZiBEZW5vICE9PSBcInVuZGVmaW5lZFwiICYmIC8vIEB0cy1leHBlY3QtZXJyb3JcbiAgdHlwZW9mIERlbm8udmVyc2lvbiAhPT0gXCJ1bmRlZmluZWRcIiAmJiAvLyBAdHMtZXhwZWN0LWVycm9yXG4gIHR5cGVvZiBEZW5vLnZlcnNpb24uZGVubyAhPT0gXCJ1bmRlZmluZWRcIlxuKTtcbmV4cG9ydCB7XG4gIGlzQnJvd3NlcixcbiAgaXNEZW5vLFxuICBpc0pzRG9tLFxuICBpc05vZGUsXG4gIGlzV2ViV29ya2VyXG59O1xuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9\n//# sourceURL=webpack-internal:///(ssr)/./node_modules/browser-or-node/dist/index.mjs\n");

/***/ })

};
;