define(["require", "exports", "tslib", "module", "react", "apmui/page/messageBox/View"],
    function (require, exports, tslib, module, React, DefaultMessageBoxView) {
        "use strict";
        Object.defineProperty(exports, "__esModule", { value: true });
        requirejs.config({
            map: {
                // Override messagebox view component when it is loaded from
                // main View
                'apmui/master/View': {
                    // `module.id` is a reference to current module; replace
                    // with exact module name when using named define syntax
                    'apmui/page/messageBox/View': module.id,
                },
            },
        });

        var CustomMessageBoxView = function(_super) {
            function MessageBoxView() {
                return _super ? _super.apply(this, arguments) : this;
            }
            tslib.__extends(MessageBoxView, _super);

            // React lifecycle method. Is invoked immediately after a component
            // is mounted (inserted into the tree)
            MessageBoxView.prototype.componentDidMount = function() {
                if (window.QRCode) {
                    // Create instance of QRCode class from "qrcode.js" file
                    this._qrCodeObj = new window.QRCode(document.getElementById('qrcode'), "otpauth://totp/%{session.custom.otp.qr_uri}");
                } else {
                    console.error("File qrcode.js was not properly loaded");
                }
            };

            // React lifecycle method. Is invoked immediately before a component
            // is unmounted and destroyed
            MessageBoxView.prototype.componentWillUnmount = function() {
                if (this._qrCodeObj) {
                    this._qrCodeObj.clear();
                }
            };

            MessageBoxView.prototype.render = function() {
                return React.createElement(DefaultMessageBoxView.default, tslib.__assign({}, this.props));
            };

            return MessageBoxView;

        }(React.Component);

        exports.default = CustomMessageBoxView;
    }
);
