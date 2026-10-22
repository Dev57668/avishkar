def infer(model, x):
    model.eval()
    return model(x)
