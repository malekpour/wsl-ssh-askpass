fn main() {
    // Embed the Windows manifest for ComCtl32 v6 and dark mode support
    embed_resource::compile("app.rc", embed_resource::NONE);
}
