// /** @odoo-module **/

//TODO: do it later

// import { qweb } from "web.core";
// import public_widget from "web.public.widget";
// import { handleCheckIdentity } from "portal.portal";
// import Dialog from "web.Dialog";

// export default public_widget.registry.t4_auth_security_email =
//   public_widget.Widget.extend({
//     selector: "#email_update_btn",
//     events: {
//       click: "_onClick",
//     },
//     async _onClick(e) {

//       e.preventDefault();
//       const w = await handleCheckIdentity(
//         this.proxy("_rpc"),
//         this._rpc({
//           model: "res.users",
//           method: "action_change_email_wizard",
//           args: [this.getSession().user_id],
//         })
//       );
//       if (!w) {
//         window.location = window.location;
//         return;
//       }
//       //
//       const { res_model: model, res_id: wizard_id } = w;
//       const record = await this._rpc({
//         model,
//         method: "read",
//         args: [wizard_id, []],
//       }).then((ar) => ar[0]);
//       const doc = new DOMParser().parseFromString(
//         document.getElementById("t4_auth_email_wizard_view").textContent,
//         "application/xhtml+xml"
//       );
//       const body = doc.querySelector("sheet *");
//       const $content = document.createElement("form");
//       $content.appendChild(body);
//       $content.addEventListener("submit", (e) => {
//         e.preventDefault();
//         dialog.$footer.find(".btn-primary").click();
//       });
//       let dialog = new Dialog(this, { $content }).open();
//     },
//   });
