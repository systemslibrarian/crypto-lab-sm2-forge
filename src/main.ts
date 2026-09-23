import './styles.css';
import { renderApp } from './ui/app';

const app = document.querySelector<HTMLElement>('#app');

if (!app) {
  throw new Error('Missing #app mount point');
}

renderApp(app);