const {chromium} = require('playwright');
const fs = require('fs');
const assert = require('node:assert/strict');
(async () => {
 const browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium',headless:true});
 try {
  const context = await browser.newContext();
  const guard = fs.readFileSync(require('node:path').join(__dirname, '../template/single_tab.html'),'utf8');
  await context.route('http://localhost/**', route => route.fulfill({contentType:'text/html; charset=utf-8', body:`<!doctype html><html><head>${guard}</head><body><form><button>Guardar</button></form><a href="/next">Continuar</a></body></html>`}));
  const first = await context.newPage(); await first.goto('http://localhost/');
  await first.waitForSelector('html[data-tab-active]');
  const second = await context.newPage(); await second.goto('http://localhost/');
  await second.getByText('La aplicación ya está abierta', {exact:false}).waitFor();
  assert.equal(await second.locator('form').isVisible(),false);
  assert.equal(await second.evaluate(() => { const e=new Event('submit',{cancelable:true,bubbles:true});document.querySelector('form').dispatchEvent(e);return e.defaultPrevented; }),true);
  await first.reload(); await first.waitForSelector('html[data-tab-active]');
  await first.getByText('Continuar').click(); await first.waitForSelector('html[data-tab-active]');
  await first.goBack(); await first.waitForSelector('html[data-tab-active]');
  await first.close(); await second.getByText('Reintentar',{exact:true}).click();
  await second.waitForSelector('html[data-tab-active]');
  const unsupported = await browser.newContext();
  await unsupported.addInitScript(() => Object.defineProperty(navigator,'locks',{value:undefined}));
  await unsupported.route('http://localhost/**', route => route.fulfill({contentType:'text/html; charset=utf-8',body:`<html><head>${guard}</head><body><form>Editar</form></body></html>`}));
  const third=await unsupported.newPage();await third.goto('http://localhost/');
  await third.getByText('No se puede comprobar la pestaña activa.',{exact:false}).waitFor();
  assert.equal(await third.locator('form').isVisible(),false);
  console.log('OK: exclusión, bloqueo de envío, recarga, navegación, historial, cierre/recuperación y navegador sin Web Locks.');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
