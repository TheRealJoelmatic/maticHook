# Matic Hook
This is a simple and minimal hooking library that uses syscalls.
It was made to bypass anticheat hooks (e.g., NtProtectVirtualMemory, VirtualProtect) that block access to changing the assembly, rendering libraries like MinHook unusable.

You could also use the .asm file provided in this project to update minhook to work. ([VirtualProtect in Minhook](https://github.com/TsudaKageyu/minhook/blob/c1a7c3843bd1a5fe3eb779b64c0d823bca3dc339/src/hook.c#L406))

UC thread: [https://www.unknowncheats.me/forum/combat-master/663786-hooks.html](https://www.unknowncheats.me/forum/combat-master/663786-hooks.html)
# Assembly
(The function is an standard get fov for unity)

**Not hooked**
![Not Hook Diagram](https://github.com/TheRealJoelmatic/maticHook/blob/main/imgs/no%20hooked.png?raw=true)

**Hooked**
![Not Hook Diagram](https://raw.githubusercontent.com/TheRealJoelmatic/maticHook/refs/heads/main/imgs/hooked.png)
# How to use

```C++

void WINAPI hk_weapon_sway_update(void* thisptr) {
    if (modules::noSwayEnabled) {
        //stop weapon sway
        return;
    }

    //return normal function
    return original_weapon_sway_update(thisptr);
}


void main(){
    //init library
    maticHook::init()
    
    //make hook
    lpTarget = (LPVOID)(CombatMaster::GameAssembly + Offsets::WeaponSwayUpdate);
    maticHook::create(lpTarget, hk_weapon_sway_update, reinterpret_cast<void*&>(original_weapon_sway_update));
}
```

# References 

- https://github.com/senko37/inthook/tree/main
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/system-calls?view=msvc-170

