/// <binding Clean="Run - Development" ProjectOpened="Watch - Development" />
const path = require("path");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const CssMinimizerPlugin = require("optimize-css-assets-webpack-plugin");

var BomPlugin = require("webpack-utf8-bom");

// From: https://bulma.io/documentation/customize/with-webpack/
module.exports = {
    mode: "development",
    //mode: "production",
    devtool: "inline-source-map",
    entry: [
        //"babel-polyfill",
        "./Scripts/Main.ts"
    ],
    optimization: {
        moduleIds: "deterministic",
    },
    output: {
        filename: "bundle.js",
        path: path.resolve(__dirname, "wwwroot/js/"),
        library: {
            name: "Main",
            type: "umd",
        }
    },
    target: ["web", "es3"],
    plugins: [
        new MiniCssExtractPlugin({
            filename: "../css/Main.css"
        }),
        //new CssMinimizerPlugin({
        //    cssProcessor: require("cssnano"),
        //    cssProcessorPluginOptions: {
        //        preset: ["default", {
        //            discardComments: { removeAll: true },
        //        }],
        //    },
        //}),
        new BomPlugin(true),
    ],
    module: {
        // ����: loader �͉����珇�ɓǂݍ��܂�܂��B
        rules: [
            {
                test: /\.(ts|tsx)$/,
                exclude: /node_modules/,
                use: [
                    {
                        loader: "babel-loader",
                    },
                ]
            },
            //{
            //    test: /\.(ts|tsx)$/,
            //    use: [
            //        {
            //            loader: "ts-loader",
            //        },
            //    ]
            //},
            {
                test: /\.(scss|sass)$/,
                use: [
                    {
                        loader: MiniCssExtractPlugin.loader,
                    },
                    {
                        // Bulma �� CSS �� img �� height:auto ���w�肳��Ă���AInternet Explorer �ŉ摜�T�C�Y�����������Ȃ���� CSS �𓮓I�ɂ������ĉ���
                        // https://github.com/jgthms/bulma/issues/342
                        loader: "string-replace-loader",
                        options: {
                            search: new RegExp("\\\\nimg\\,\\\\n", "g"),
                            replace: "\\n/* img, */\\n",
                        }
                    },
                    {
                        // Bulma �� CSS �� img �� height:auto ���w�肳��Ă���AInternet Explorer �ŉ摜�T�C�Y�����������Ȃ���� CSS �𓮓I�ɂ������ĉ���
                        // https://github.com/jgthms/bulma/issues/342
                        loader: "string-replace-loader",
                        options: {
                            search: new RegExp("\\\\nimg\\ \\{\\\\n", "g"),
                            replace: "\\n/* img */ dummy_img {\\n",
                        }
                    },
                    {
                        loader: "css-loader",
                        options: {
                            sourceMap: true,
                        }
                    },
                    {
                        loader: "sass-loader",
                        options: {
                            sourceMap: true,
                        }
                    },
                ]
            }]
    },
    resolve: {
        extensions: [".ts", ".js"],
        modules: [
            "node_modules",
            path.resolve(__dirname, "./Scripts/")
        ],
        fallback:
        {
            "stream": false,
            "buffer": false,
            "crypto": false
        }
    },
};


