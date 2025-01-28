from emulation.arm64_linux import emulate  # type: ignore[import-not-found]

# Example #1 of code the user might provide -- Hello World
with open("examples/arm64_linux/hello.S") as file_in:
    # Read the provided code into a string.
    hello_world = file_in.read()
    # Call the emulate function to execute the code.
    ok_results1 = emulate(code=hello_world)
    print(f"{ok_results1=}")
    print("\n")

# Example #2 of code the user might provide -- Infinite Loop
with open("examples/arm64_linux/infiniteLoop.S") as file_in:
    infinite_loop = file_in.read()
    # Call the emulate function changing its timeout.
    bad_results1 = emulate(code=infinite_loop, timeout=1_000_000)
    print(f"{bad_results1=}")
    print("\n")

# Example #3 of code the user might provide -- Taking Input
with open("examples/arm64_linux/ioExample.S") as file_in:
    io_example = file_in.read()
    # Set stdin so the user code can consume it.
    ok_results2 = emulate(code=io_example, timeout=1_000_000, stdin="hello-hello!")
    print(f"{ok_results2=}")
    print("\n")

    # We do NOT have input for the read instruction!
    # This should eventually crash, but it's fine to ignore for now.
    bad_results2 = emulate(code=io_example, timeout=1_000_000)
    print(f"{bad_results2=}")
    print("\n")
