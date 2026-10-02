// SPDX-License-Identifier: AGPL-3.0-or-later
// Authored pinned-loader registration, not generated owner UI output.
window.__ModuleLoader__.load({id:'@aukora-prime/native-host',factory(_require){
 const exports={};
 exports.inject=['primeOwnerUi','primeOwnerNativeConnection'];
 exports.apply=async function(ctx){
  const {apply}=await import('/prime/harness/native-host-client.mjs');
  await apply(ctx);
 };
 return exports;
}});
