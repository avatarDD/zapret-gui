/**
 * awg_routing.js — «AWG-правила»: отфильтрованный вид единого раздела
 * «Маршрутизация».
 *
 * Отдельной системы правил для AWG больше нет (задача №4 роадмапа):
 * правила по CIDR / доменам / устройствам / DSCP создаются в едином
 * слое (core/unified, страница routing_unified.js), где «через что»
 * (awg/sing-box/mihomo/nfqws2/direct) — свойство маршрута. Этот
 * адаптер открывает ту же страницу с предустановленным фильтром
 * «Через: AWG» — старые ссылки #awg-routing продолжают работать.
 *
 * Legacy-правила старого хранилища (routing.rules) автоматически
 * мигрируются на boot и баннером на странице (POST /api/unified/migrate).
 */

const AwgRoutingPage = {
    render(container) {
        RoutingUnifiedPage.render(container, { alias: 'awg', via: 'awg' });
    },
    destroy() {
        RoutingUnifiedPage.destroy();
    },
};
