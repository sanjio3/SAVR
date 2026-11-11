import { createApp } from "vue";
import { createPinia } from "pinia";

import App from "./App.vue";
import router from "./router";
import "github-markdown-css/github-markdown.css";
import "./styles.css";

createApp(App).use(createPinia()).use(router).mount("#app");
