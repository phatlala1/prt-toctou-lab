// NC-03 control payload. Present in the tree but never invoked, because
// package.json declares no preinstall/install/postinstall/prepare hook.
// If SAFE_PREINSTALL_EXECUTED ever appears for this stage, the control is void.
console.log('NC03_INERT_SHOULD_NEVER_RUN');
