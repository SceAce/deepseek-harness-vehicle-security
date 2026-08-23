import { fileURLToPath } from 'node:url';
import { FileSystemSkillProvider } from '@deepseek-ai/dsh-skill-filesystem';
export const name = 'ctf-skills';
export const inject = ['skills'];
const bundledSkillDir = fileURLToPath(new URL('../../codex-plugin/plugins/ctf-security/skills', import.meta.url));
export function apply(ctx) {
    let provider;
    ctx.skills.registerProvider(control => {
        provider = new FileSystemSkillProvider(ctx, control, {
            providerName: 'ctf-security',
            includeDefaultRoots: false,
            bundledSkillDir,
            watch: false,
        });
        return provider;
    });
    ctx.effect(function* () {
        yield async () => provider?.dispose();
    }, 'ctf skill provider');
}
//# sourceMappingURL=skills.js.map